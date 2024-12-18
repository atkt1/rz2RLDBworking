import React from 'react';
import { Card } from '@/components/ui/Card';
import { SectionHeader } from '@/components/ui/SectionHeader';
import { featuresList } from './features-data';

const Features = () => {
  return (
    <section id="features" className="py-12 bg-gradient-to-b from-white to-blue-50">
      <div className="container mx-auto px-4">
        <SectionHeader
          title="Everything you need to manage reviews"
          description="Powerful features to help you collect, analyze, and leverage customer reviews to grow your business."
        />

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
          {featuresList.map((feature, index) => (
            <Card
              key={index}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
            />
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;